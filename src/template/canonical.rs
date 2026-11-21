use super::*;
use crate::accounting::PoolAccounting;
use crate::primitives::hex_encode;

// Additive TP messages introduced after the public hyphen-transport revision.
#[derive(Clone, Message)]
struct CanonicalHashesRequest {
    #[prost(message, optional, tag = "1")]
    chain: Option<TemplateRequest>,
    #[prost(uint64, repeated, tag = "2")]
    heights: Vec<u64>,
}

#[derive(Clone, Message)]
struct CanonicalHashesResult {
    #[prost(uint64, tag = "1")]
    request_nonce: u64,
    #[prost(uint64, tag = "2")]
    tip_height: u64,
    #[prost(bytes = "vec", tag = "3")]
    tip_hash: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    hashes: Vec<Vec<u8>>,
}

impl TemplateProviderClient {
    async fn canonical_hashes(&self, heights: &[u64]) -> Result<CanonicalHashesResult, TPError> {
        let request = CanonicalHashesRequest {
            chain: Some(self.identity_request()),
            heights: heights.to_vec(),
        };
        let env = SignedEnvelope::sign(121, request.encode_to_vec(), &self.sk);
        let nonce = env.nonce;
        let response = self.request_response(env, 122).await?;
        let result = CanonicalHashesResult::decode(&response.payload[..])?;
        if result.request_nonce != nonce
            || result.tip_hash.len() != 32
            || result.hashes.len() != heights.len()
            || result.hashes.iter().zip(heights).any(|(hash, height)| {
                if *height <= result.tip_height {
                    hash.len() != 32
                } else {
                    !hash.is_empty()
                }
            })
        {
            return Err(TPError::Protocol("invalid canonical hash response".into()));
        }
        Ok(result)
    }

    pub async fn reconcile_rewards(&self, accounting: &PoolAccounting) -> Result<(), String> {
        let mut anchor = self.reward_anchor.lock().await;
        let previous = anchor.take();
        let dirty = accounting.begin_reward_scan();
        let probe: Vec<_> = previous.iter().map(|(height, _)| *height).collect();
        let tip = self
            .canonical_hashes(&probe)
            .await
            .map_err(|e| e.to_string())?;
        let mut next = 0;
        if let Some((height, hash)) = previous
            && tip.hashes.first() == Some(&hash)
        {
            next = height.saturating_add(1).min(dirty.unwrap_or(u64::MAX));
        }
        loop {
            let mut heights = accounting
                .reward_heights(next, 127)
                .map_err(|e| e.to_string())?;
            if heights.is_empty() {
                break;
            }
            let last = *heights.last().expect("nonempty height batch");
            heights.push(tip.tip_height);
            let mut page = self
                .canonical_hashes(&heights)
                .await
                .map_err(|e| e.to_string())?;
            if page.hashes.pop().as_ref() != Some(&tip.tip_hash) {
                return Err("chain changed during reward reconciliation".into());
            }
            for (height, hash) in heights.into_iter().zip(page.hashes) {
                let hash = if height <= tip.tip_height {
                    hex_encode(hash)
                } else {
                    String::new()
                };
                accounting
                    .reconcile_reward_height(height, &hash)
                    .map_err(|e| e.to_string())?;
            }
            let Some(following) = last.checked_add(1) else {
                break;
            };
            next = following;
        }
        if !accounting.finish_reward_scan() {
            return Err("pool settled a block during reward reconciliation".into());
        }
        *anchor = Some((tip.tip_height, tip.tip_hash));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PoolAccountingConfig, PoolMode};

    #[tokio::test]
    async fn old_provider_and_mismatched_replies_keep_reservations_closed() {
        let cfg = ChainConfig::archived_devnet_v2();
        let directory =
            std::env::temp_dir().join(format!("hyphen-provider-reply-{}", crate::random_u64()));
        let accounting = PoolAccounting::new(PoolAccountingConfig {
            network_magic: cfg.network_magic,
            mode: PoolMode::Pps,
            pool_fee_bps: 100,
            pool_wallet: [0; 32],
            pool_view_public: [0; 32],
            pplns_window_factor: 2,
            state_dir: Some(directory.clone()),
        });
        let miner = [1; 32];
        accounting.register_view_key(miner, [2; 32]).unwrap();
        accounting.register_miner(miner, miner);
        accounting.record_valid_share(miner, miner, 1, 1, 100, 0);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let provider = tokio::spawn(async move {
            let key = SecretKey::generate();
            for (kind, wrong_nonce) in [(TP_TEMPLATE, false), (122, true), (122, false)] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_envelope(&mut stream).await.unwrap();
                assert_eq!(request.msg_type, 121);
                let result = CanonicalHashesResult {
                    tip_hash: vec![1; 32],
                    request_nonce: request.nonce ^ u64::from(wrong_nonce),
                    ..Default::default()
                };
                write_envelope(
                    &mut stream,
                    &SignedEnvelope::sign(kind, result.encode_to_vec(), &key),
                )
                .await
                .unwrap();
            }
        });
        for succeeds in [false, false, true] {
            let client = TemplateProviderClient::connect(&addr, &SecretKey::generate(), &cfg)
                .await
                .unwrap();
            assert_eq!(
                client.reconcile_rewards(&accounting).await.is_ok(),
                succeeds
            );
            assert_eq!(
                accounting.reserve_payout(1, 10, true).unwrap().is_some(),
                succeeds
            );
        }
        provider.await.unwrap();
        drop(accounting);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
