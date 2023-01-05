use surrealdb::Datastore;
use surrealdb::Error;
use surrealdb::Session;

async fn create_person(ds: &Datastore, session: &Session) -> Result<(), Error>{
    let create_query = "USE NS test DB test; CREATE person SET
        name = 'anything',
        created_at = time::now()
    ;";
    let create_response = ds.execute(create_query, session, None, false).await?;
    let create_result = &create_response[1].result;
    println!("Create response {:?}", create_response);
    Ok(())
}

async fn fetch_persons(ds: &Datastore, session: &Session) -> Result<(), Error>{
    let fetch_query = "USE NS test DB test; SELECT * FROM person;";
    let fetch_response = ds.execute(fetch_query, session, None, false).await?;
    let fetch_response = &fetch_response[1].result;
    println!("Fetch response {:?}", fetch_response);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let ds = Datastore::new("file://database.db").await?;
    let root_session = Session::for_kv();

    // create_person(&ds, &root_session).await?;

    fetch_persons(&ds, &root_session).await?;

    Ok(())
}