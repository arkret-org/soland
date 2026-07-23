use std::fmt::{self, Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};

use salvo::extract::{Extractible, Metadata};
use salvo::http::ParseError;
use salvo::{Depot, Request, Writer};
use serde::{Deserialize, Deserializer};

/// A JSON request body extracted without coupling runtime handlers to OpenAPI.
pub struct JsonBody<T>(pub T);

impl<T> JsonBody<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for JsonBody<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for JsonBody<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Debug> Debug for JsonBody<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Display> Display for JsonBody<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de, T> Deserialize<'de> for JsonBody<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

impl<'ex, T> Extractible<'ex> for JsonBody<T>
where
    T: Deserialize<'ex> + Send,
{
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    async fn extract(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
    ) -> Result<Self, impl Writer + Send + Debug + 'static> {
        req.parse_json().await
    }

    async fn extract_with_arg(
        req: &'ex mut Request,
        depot: &'ex mut Depot,
        _arg: &str,
    ) -> Result<Self, impl Writer + Send + Debug + 'static> {
        Self::extract(req, depot).await
    }
}

/// A typed path parameter extracted by the handler argument name.
pub struct PathParam<T>(pub T);

impl<T> PathParam<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for PathParam<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for PathParam<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Debug> Debug for PathParam<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Display> Display for PathParam<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de, T> Deserialize<'de> for PathParam<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

impl<'ex, T> Extractible<'ex> for PathParam<T>
where
    T: Deserialize<'ex>,
{
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(_req: &'ex mut Request, _depot: &'ex mut Depot) -> Result<Self, ParseError> {
        unreachable!("path parameters require a handler argument name")
    }

    #[allow(refining_impl_trait)]
    async fn extract_with_arg(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
        arg: &str,
    ) -> Result<Self, ParseError> {
        req.param(arg).map(Self).ok_or_else(|| {
            ParseError::other(format!(
                "path parameter {arg} not found or convert to type failed"
            ))
        })
    }
}

/// A typed query parameter extracted by the handler argument name.
pub struct QueryParam<T, const REQUIRED: bool = true>(Option<T>);

impl<T> QueryParam<T, true> {
    pub fn into_inner(self) -> T {
        self.0
            .expect("required query parameter must be present after extraction")
    }
}

impl<T> QueryParam<T, false> {
    pub fn into_inner(self) -> Option<T> {
        self.0
    }
}

impl<T> Deref for QueryParam<T, true> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("required query parameter must be present after extraction")
    }
}

impl<T> Deref for QueryParam<T, false> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for QueryParam<T, true> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .as_mut()
            .expect("required query parameter must be present after extraction")
    }
}

impl<T> DerefMut for QueryParam<T, false> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Debug, const REQUIRED: bool> Debug for QueryParam<T, REQUIRED> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Display> Display for QueryParam<T, true> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0
            .as_ref()
            .expect("required query parameter must be present after extraction")
            .fmt(f)
    }
}

impl<'de, T, const REQUIRED: bool> Deserialize<'de> for QueryParam<T, REQUIRED>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

impl<'ex, T> Extractible<'ex> for QueryParam<T, true>
where
    T: Deserialize<'ex>,
{
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(_req: &'ex mut Request, _depot: &'ex mut Depot) -> Result<Self, ParseError> {
        unreachable!("query parameters require a handler argument name")
    }

    #[allow(refining_impl_trait)]
    async fn extract_with_arg(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
        arg: &str,
    ) -> Result<Self, ParseError> {
        req.query(arg)
            .map(|value| Self(Some(value)))
            .ok_or_else(|| {
                ParseError::other(format!(
                    "query parameter {arg} not found or convert to type failed"
                ))
            })
    }
}

impl<'ex, T> Extractible<'ex> for QueryParam<T, false>
where
    T: Deserialize<'ex>,
{
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(_req: &'ex mut Request, _depot: &'ex mut Depot) -> Result<Self, ParseError> {
        unreachable!("query parameters require a handler argument name")
    }

    #[allow(refining_impl_trait)]
    async fn extract_with_arg(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
        arg: &str,
    ) -> Result<Self, ParseError> {
        Ok(Self(req.query(arg)))
    }
}

#[cfg(test)]
mod tests {
    use salvo::Depot;
    use salvo::extract::Extractible;
    use salvo::test::TestClient;
    use serde::Deserialize;

    use super::{JsonBody, PathParam, QueryParam};

    #[derive(Debug, Deserialize, PartialEq)]
    struct ExampleBody {
        value: String,
    }

    #[tokio::test]
    async fn extracts_json_body() {
        let mut request = TestClient::post("http://127.0.0.1/")
            .json(&serde_json::json!({"value": "ok"}))
            .build();
        let mut depot = Depot::new();

        let body = JsonBody::<ExampleBody>::extract(&mut request, &mut depot)
            .await
            .expect("JSON body should parse");

        assert_eq!(
            body.into_inner(),
            ExampleBody {
                value: "ok".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn extracts_named_path_parameter() {
        let mut request = salvo::Request::new();
        request.params_mut().insert("item_id", "item-1".to_owned());
        let mut depot = Depot::new();

        let item_id = PathParam::<String>::extract_with_arg(&mut request, &mut depot, "item_id")
            .await
            .expect("path parameter should parse");

        assert_eq!(item_id.into_inner(), "item-1");
    }

    #[tokio::test]
    async fn distinguishes_required_and_optional_query_parameters() {
        let mut request = TestClient::get("http://127.0.0.1/?limit=10").build();
        let mut depot = Depot::new();

        let limit = QueryParam::<u32, true>::extract_with_arg(&mut request, &mut depot, "limit")
            .await
            .expect("required query parameter should parse");
        let cursor =
            QueryParam::<String, false>::extract_with_arg(&mut request, &mut depot, "cursor")
                .await
                .expect("missing optional query parameter should parse");

        assert_eq!(limit.into_inner(), 10);
        assert_eq!(cursor.into_inner(), None);
    }
}
