use super::*;

#[derive(Default)]
struct RewardScan {
    dirty_from: Option<u64>,
    verified: bool,
}

const INCLUSION: TableDefinition<(u64, &str), bool> = TableDefinition::new("reward_inclusion_v1");
pub(super) const EVENTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("original_reward_events_v1");
const DEBITS: TableDefinition<&str, u128> = TableDefinition::new("detached_reward_debits_v1");

pub(super) struct RewardAccounting {
    pub(super) debits: RwLock<BTreeMap<String, u128>>,
    scan: parking_lot::Mutex<RewardScan>,
}

impl RewardAccounting {
    pub(super) fn open(
        write: &WriteTransaction,
        state: &AccountingState,
    ) -> Result<Self, AccountingError> {
        let mut credits = write.open_table(BLOCK_CREDITS).map_err(storage_error)?;
        let mut ledger = write.open_table(LEDGER).map_err(storage_error)?;
        if ledger
            .get("reward_index_v1")
            .map_err(storage_error)?
            .is_none()
        {
            let mut index = write.open_table(INCLUSION).map_err(storage_error)?;
            for item in credits.iter().map_err(storage_error)? {
                let (key, bytes) = item.map_err(storage_error)?;
                let record: BlockCredits = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .deserialize(bytes.value())
                    .map_err(storage_error)?;
                index
                    .insert((record.settlement.height, key.value()), true)
                    .map_err(storage_error)?;
            }
            let mut events_table = write.open_table(EVENTS).map_err(storage_error)?;
            for block in &state.recent_blocks {
                let hash = block.block_hash_hex.as_str();
                index
                    .insert((block.height, hash), true)
                    .map_err(storage_error)?;
                let events: Vec<_> = state
                    .reward_events
                    .iter()
                    .filter(|event| event.block_hash_hex == hash)
                    .cloned()
                    .collect();
                let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .serialize(&events)
                    .map_err(storage_error)?;
                events_table
                    .insert(hash, bytes.as_slice())
                    .map_err(storage_error)?;
                if credits.get(hash).map_err(storage_error)?.is_none()
                    && (block.direct_coinbase || block.distributed_atomic == 0)
                {
                    let record = BlockCredits {
                        settlement: block.clone(),
                        pending_by_miner: BTreeMap::new(),
                    };
                    let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                        .serialize(&record)
                        .map_err(storage_error)?;
                    credits
                        .insert(hash, bytes.as_slice())
                        .map_err(storage_error)?;
                }
            }
            ledger
                .insert("reward_index_v1", &[1u8][..])
                .map_err(storage_error)?;
        }
        let table = write.open_table(DEBITS).map_err(storage_error)?;
        let mut debits = BTreeMap::new();
        for item in table.iter().map_err(storage_error)? {
            let (key, value) = item.map_err(storage_error)?;
            debits.insert(key.value().to_owned(), value.value());
        }
        Ok(Self {
            debits: RwLock::new(debits),
            scan: parking_lot::Mutex::default(),
        })
    }

    pub(super) fn record(
        write: &WriteTransaction,
        height: u64,
        hash: &str,
        events: &Vec<WalletRewardEvent>,
    ) -> Result<(), AccountingError> {
        write
            .open_table(INCLUSION)
            .map_err(storage_error)?
            .insert((height, hash), true)
            .map_err(storage_error)?;
        let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(events)
            .map_err(storage_error)?;
        write
            .open_table(EVENTS)
            .map_err(storage_error)?
            .insert(hash, bytes.as_slice())
            .map_err(storage_error)?;
        Ok(())
    }

    pub(super) fn invalidate_scan(&self, height: u64) {
        let mut scan = self.scan.lock();
        scan.verified = false;
        scan.dirty_from = Some(scan.dirty_from.map_or(height, |first| first.min(height)));
    }
}

impl PoolAccounting {
    pub(crate) fn begin_reward_scan(&self) -> Option<u64> {
        // Consume invalidations only after the corresponding settlement has finished.
        let _state = self.state.read();
        let mut scan = self.rewards.scan.lock();
        scan.verified = false;
        scan.dirty_from.take()
    }

    pub(crate) fn finish_reward_scan(&self) -> bool {
        let mut scan = self.rewards.scan.lock();
        scan.verified = scan.dirty_from.is_none();
        scan.verified
    }

    pub(super) fn rewards_verified(&self) -> bool {
        self.rewards.scan.lock().verified
    }

    pub(crate) fn reward_heights(
        &self,
        from: u64,
        limit: usize,
    ) -> Result<Vec<u64>, AccountingError> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let index = read.open_table(INCLUSION).map_err(storage_error)?;
        let mut heights = Vec::with_capacity(limit);
        for item in index.range((from, "")..).map_err(storage_error)? {
            let height = item.map_err(storage_error)?.0.value().0;
            if heights.last() != Some(&height) {
                heights.push(height);
            }
            if heights.len() == limit {
                break;
            }
        }
        Ok(heights)
    }

    pub(crate) fn reconcile_reward_height(
        &self,
        height: u64,
        canonical: &str,
    ) -> Result<(), AccountingError> {
        let mut current = self.state.write();
        let read = self.db.begin_read().map_err(storage_error)?;
        let changes = Self::reward_changes(&read, height, canonical)?;
        if changes.is_empty() {
            return Ok(());
        }

        let mut next = current.clone();
        let write = self.db.begin_write().map_err(storage_error)?;
        let balances = self.apply_reward_changes(&read, &write, height, changes, &mut next)?;
        Self::commit_state(write, &next)?;
        *current = next;
        *self.rewards.debits.write() = balances;
        Ok(())
    }

    pub(super) fn reward_changes(
        read: &redb::ReadTransaction,
        height: u64,
        canonical: &str,
    ) -> Result<Vec<(String, bool)>, AccountingError> {
        let index = read.open_table(INCLUSION).map_err(storage_error)?;
        let mut changes = Vec::new();
        for item in index
            .range((height, "")..=(height, "\u{10ffff}"))
            .map_err(storage_error)?
        {
            let (key, value) = item.map_err(storage_error)?;
            let hash = key.value().1;
            let attach = hash == canonical;
            if attach != value.value() {
                changes.push((hash.to_owned(), attach));
            }
        }
        changes.sort_by_key(|(_, attach)| *attach);
        Ok(changes)
    }

    pub(super) fn apply_reward_changes(
        &self,
        read: &redb::ReadTransaction,
        write: &WriteTransaction,
        height: u64,
        changes: Vec<(String, bool)>,
        next: &mut AccountingState,
    ) -> Result<BTreeMap<String, u128>, AccountingError> {
        let mut balances = self.rewards.debits.read().clone();
        let credits = read.open_table(BLOCK_CREDITS).map_err(storage_error)?;
        let events = read.open_table(EVENTS).map_err(storage_error)?;
        for (hash, attach) in changes {
            let bytes = credits
                .get(hash.as_str())
                .map_err(storage_error)?
                .ok_or_else(|| {
                    storage_error(format!(
                        "missing original miner allocations for legacy block {height} {hash}"
                    ))
                })?;
            let record: BlockCredits = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .deserialize(bytes.value())
                .map_err(storage_error)?;
            let block = record.settlement;
            if block.height != height || block.block_hash_hex != hash {
                return Err(storage_error("reward index identity mismatch"));
            }
            let finder = next
                .miners
                .get_mut(&hex_encode(block.finder_pubkey))
                .ok_or_else(|| storage_error("reward finder missing from ledger"))?;
            finder.total_blocks_found = if attach {
                finder.total_blocks_found.checked_add(1)
            } else {
                finder.total_blocks_found.checked_sub(1)
            }
            .ok_or_else(|| storage_error("invalid finder block count"))?;
            if block.direct_coinbase {
                adjust(
                    &mut finder.direct_reward_atomic,
                    block.gross_reward_atomic.into(),
                    attach,
                )?;
            }
            adjust(
                &mut next.pool_fee_earned_atomic,
                block.pool_fee_atomic,
                attach,
            )?;
            if matches!(block.mode, PoolMode::Prop | PoolMode::Pplns) {
                let mut table = write.open_table(DEBITS).map_err(storage_error)?;
                for (key, amount) in record.pending_by_miner {
                    let balance = balances.entry(key.clone()).or_default();
                    adjust(balance, amount, !attach)?;
                    if *balance == 0 {
                        table.remove(key.as_str()).map_err(storage_error)?;
                        balances.remove(&key);
                    } else {
                        table
                            .insert(key.as_str(), *balance)
                            .map_err(storage_error)?;
                    }
                }
            }
            if attach {
                next.recent_blocks.push(block);
                if let Some(bytes) = events.get(hash.as_str()).map_err(storage_error)? {
                    let original: Vec<WalletRewardEvent> =
                        crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                            .deserialize(bytes.value())
                            .map_err(storage_error)?;
                    next.reward_events.extend(original);
                }
            } else {
                next.recent_blocks
                    .retain(|block| block.block_hash_hex != hash);
                next.reward_events
                    .retain(|event| event.block_hash_hex != hash);
            }
            write
                .open_table(INCLUSION)
                .map_err(storage_error)?
                .insert((height, hash.as_str()), attach)
                .map_err(storage_error)?;
        }
        next.recent_blocks.sort_by_key(|block| block.height);
        next.recent_blocks
            .drain(..next.recent_blocks.len().saturating_sub(128));
        next.reward_events.sort_by_key(|event| event.height);
        next.reward_events
            .drain(..next.reward_events.len().saturating_sub(512));
        Ok(balances)
    }
}

fn adjust(balance: &mut u128, amount: u128, increase: bool) -> Result<(), AccountingError> {
    *balance = if increase {
        balance.checked_add(amount)
    } else {
        balance.checked_sub(amount)
    }
    .ok_or_else(|| storage_error("reward adjustment exceeds accounting balance"))?;
    Ok(())
}
