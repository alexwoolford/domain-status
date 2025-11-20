// Quick test to understand the API
use whois_service::WhoisClient;

#[tokio::main]
async fn main() {
    let client = WhoisClient::new();
    let result = client.lookup("example.com").await;
    println!("Result: {:?}", result);
}
