//! Template Protocol surface. The wire types are the node's canonical
//! `hyphen-transport` definitions; owning a second copy is how the pool and
//! the node drift apart without anyone noticing.

pub use hyphen_transport::{
    read_envelope, write_envelope, BlockTemplate, DeclareJobRequest, DeclareJobResult,
    SignedEnvelope, SubmitBlockRequest, SubmitBlockResult, TPError, TemplateInvalidated,
    TemplateProvider, TemplateRequest, TP_DECLARE_JOB, TP_DECLARE_JOB_RESULT, TP_GET_TEMPLATE,
    TP_SUBMIT_BLOCK, TP_SUBMIT_RESULT, TP_SUBSCRIBE, TP_TEMPLATE, TP_TEMPLATE_INVALIDATED,
    TP_UNSUBSCRIBE,
};
