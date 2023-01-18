// use db::Database;
use db::User;

use surrealdb::Error;
// use surrealdb::Session;


#[tokio::main]
async fn main() -> Result<(), Error> {
    User::create_obj("username", "email", "password");

    Ok(())
}