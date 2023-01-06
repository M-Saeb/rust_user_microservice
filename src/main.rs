use db::Database;
use db::User;

use surrealdb::Error;
use surrealdb::Session;


#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut db = Database::connect(
        "file://database.db",
        "test", "test"
    ).await?;
    let root_session = Session::for_kv();
    db.set_session(root_session).await;

    let response = db.excute("SELECT * FROM person;").await?;

    println!("{:?}", response);

    Ok(())
}