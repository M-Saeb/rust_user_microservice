mod utils;

use db::User;
// use crate::utils::vec_response_to_single_object;

use surrealdb::Error;
// use surrealdb::Session;


#[tokio::main]
async fn main() -> Result<(), Error> {
    User::create_obj("username", "email", "password");

    Ok(())
}