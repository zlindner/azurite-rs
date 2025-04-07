#[derive(Debug, clap::Parser)]
pub struct Config {
    /// The account kind used by the emulator.
    /// The possible values are Storage, BlobStorage, and StorageV2.
    /// See: https://learn.microsoft.com/en-us/rest/api/storagerp/srp_sku_types
    #[clap(env, long)]
    pub account_kind: String,

    /// The SKU type used by the emulator.
    /// See: https://learn.microsoft.com/en-us/rest/api/storagerp/srp_sku_types
    #[clap(env, long)]
    pub account_sku: String,

    /// The version of Azure Blob Storage used by the emulator.
    #[clap(env, long)]
    pub account_version: String,

    /// Indicates if the emulator has a hierarchical namespace enabled.
    /// Requires Version 2019-07-07 and later.
    #[clap(env, long)]
    pub account_hns_enabled: bool,

    /// The base64 encoded key used to authorize requests to the emulator.
    #[clap(env, long)]
    pub account_key: String,

    /// The http server port used by the blob service.
    #[clap(env, long)]
    pub blob_server_port: String,

    /// The http server port used by the queue service.
    #[clap(env, long)]
    pub queue_server_port: String,

    /// The http server port used by the table service.
    #[clap(env, long)]
    pub table_server_port: String,
}
