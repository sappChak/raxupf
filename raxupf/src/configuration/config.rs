use config::builder::DefaultState;
use serde_aux::field_attributes::deserialize_number_from_string;
use crate::configuration::environment::Environment;

#[derive(serde::Deserialize)]
pub struct Configuration {
    pub pfcp: PfcpConfiguration,
    // pub gtpu: GtpuConfiguration,
    pub api: ApiConfiguration,
    pub logger: LoggerConfiguration,
}

#[derive(serde::Deserialize)]
pub struct PfcpConfiguration {
    pub addr: String,
    pub node_id: String,
    pub ret_timeout: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub max_ret: u32,
}

#[derive(serde::Deserialize)]
pub struct GtpuConfiguration {
    pub interface: String,
}

#[derive(serde::Deserialize)]
pub struct ApiConfiguration {
    pub addr: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub prefix: String,
}

#[derive(serde::Deserialize)]
pub struct LoggerConfiguration {
    pub name: String,
    pub level: String,
}

pub fn get_configuration() -> Result<Configuration, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to get current directory.");
    let config_directory = base_path.join("config");

    let builder = config::ConfigBuilder::<DefaultState>::default()
        .add_source(config::File::from(config_directory.join("base")).required(true));

    let environment: Environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to read APP_ENV");

    let config = builder
        .add_source(config::File::from(config_directory.join(environment.as_str())).required(true))
        .add_source(config::Environment::with_prefix("app").separator("__"))
        .build()?;

    config.try_deserialize::<Configuration>()
}
