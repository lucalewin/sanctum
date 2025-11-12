use sanctum_shared::models::{CreateRecordRequest, CreateVaultRequest, Record, Vault};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::Error;

#[derive(Debug)]
pub struct ApiClient {
    base_url: String,
    access_token: String,
    client: reqwest::Client,
}

#[allow(unused)]
impl ApiClient {
    pub fn new(base_url: String, access_token: String) -> Self {
        Self {
            base_url,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, Error> {
        let response = request
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| Error::ApiError(e))?;

        let data = response
            .error_for_status()
            .map_err(|e| Error::ApiError(e))?
            .json()
            .await
            .map_err(|e| Error::ApiError(e))?;

        Ok(data)
    }

    async fn request_empty(&self, request: reqwest::RequestBuilder) -> Result<(), Error> {
        request
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| Error::ApiError(e))?
            .error_for_status()
            .map_err(|e| Error::ApiError(e))?;
        Ok(())
    }

    pub async fn fetch_vaults(&self) -> Result<Vec<Vault>, Error> {
        let url = format!("{}/api/v1/vaults", &self.base_url);
        self.request_json(self.client.get(url)).await
    }

    pub async fn fetch_vault(&self, id: &Uuid) -> Result<Vault, Error> {
        let url = format!("{}/api/v1/vaults/{}", &self.base_url, id);
        self.request_json(self.client.get(url)).await
    }

    pub async fn create_vault(&self, vault: &CreateVaultRequest) -> Result<Vault, Error> {
        let url = format!("{}/api/v1/vaults", &self.base_url);
        self.request_json(self.client.post(url).json(vault)).await
    }

    pub async fn update_vault(&self, vault: &CreateRecordRequest) -> Result<Vault, Error> {
        todo!()
    }

    pub async fn delete_vault(&self, id: &Uuid) -> Result<(), Error> {
        let url = format!("{}/api/v1/vaults/{}", &self.base_url, id);
        self.request_empty(self.client.delete(url)).await
    }

    pub async fn fetch_records(&self, vault_id: &Uuid) -> Result<Vec<Record>, Error> {
        let url = format!("{}/api/v1/vaults/{}/records", &self.base_url, vault_id);
        self.request_json(self.client.get(url)).await
    }

    pub async fn fetch_record(&self, vault_id: &Uuid, record_id: &Uuid) -> Result<Record, Error> {
        let url = format!(
            "{}/api/v1/vaults/{}/records/{}",
            &self.base_url, vault_id, record_id
        );
        self.request_json(self.client.get(url)).await
    }

    pub async fn create_record(
        &self,
        vault_id: &Uuid,
        record: &CreateRecordRequest,
    ) -> Result<Record, Error> {
        let url = format!("{}/api/v1/vaults/{}/records", &self.base_url, vault_id);
        self.request_json(self.client.post(url).json(record)).await
    }

    pub async fn update_record(&self, vault_id: &Uuid, record_id: &Uuid) -> Result<Record, Error> {
        todo!()
    }

    pub async fn delete_record(&self, vault_id: &Uuid, record_id: &Uuid) -> Result<(), Error> {
        let url = format!(
            "{}/api/v1/vaults/{}/records/{}",
            &self.base_url, vault_id, record_id
        );
        self.request_empty(self.client.delete(url)).await
    }
}
