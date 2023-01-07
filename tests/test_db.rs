use db::{Database, User};

use surrealdb::Error;
use surrealdb::Session;

#[tokio::test]
async fn test_db_connection(){
	let db = Database::connect("memory", "test", "test").await;
}

async fn create_db_with_root_session() -> Result<Database, Error>{
	let mut db = Database::connect("memory", "test", "test").await?;
	db.set_session( Session::for_kv() ).await;
	Ok(db)
}

async fn create_user(db: Database) -> Result<User, Error>{
	let user = User::create(
		"username", "email", "password",
	);
	return db.create_user(user).await?;
}

#[tokio::test]
async fn test_user_register() -> Result<(), Error>{
	let mut db = create_db_with_root_session().await?;
	let to_create_user = User::create(
		"username", "email", "password",
	);
	let created_user = db.create_user(to_create_user).await?;
	assert_eq!(created_user.username, to_create_user.username);
	assert_eq!(created_user.email, to_create_user.email);

	Ok(())
}

#[tokio::test]
async fn test_login_user() -> Result<(), Error>{
	let mut db = create_db_with_root_session().await?;
	create_user(db).await?;
	let logged_in_user = db.user_login("username", "password").await?;
	assert!(logged_in_user);
}

