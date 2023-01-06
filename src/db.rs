use surrealdb::Datastore;
use surrealdb::Session;
use surrealdb::Response;
use surrealdb::Error;


pub struct User{
	username: String,
	email: String,
	password: String
}

impl User {
	pub fn generate_create_query(&self) -> String {
		let query = format!("
			CREATE user SET
			username = '{}',
			email = '{}',
			password = '{}',
			created_on = time::now(),

		", self.username, self.email, self.password);
		query
	}
}

pub struct Database{
	datastore: Datastore,
	surreal_ns: String,
	surreal_db: String,
	session: Option<Session>,
}


impl Database {
	pub async fn connect(path: &str, ns: & str, db: & str) -> Result<Database, Error> {
		let dt = Datastore::new(path).await?;
		let db = Database{
			datastore: dt,
			surreal_ns: ns.to_owned(),
			surreal_db: db.to_owned(),
			session: None
		};
		Ok(db)
	}

	pub async fn set_session(&mut self, session: Session) {
		self.session = Some(session);
	}

	pub async fn excute(&mut self, query: &str) -> Result<Vec<Response>, Error>{
		let init_query = format!("USE NS {} DB {}; ", self.surreal_ns, self.surreal_db );
		let full_query = init_query + query;
		let session = self.session.as_ref().expect("You forget to set session");
	    let response = self.datastore.execute(
			full_query.as_str(),
			session,
			None,
			false
		).await?;
		Ok(response)

	}

	pub async fn create_user(&mut self, user: User) -> Result<Vec<Response>, Error>{
		let query = user.generate_create_query();
		let response = self.excute(query.as_ref()).await?;
		Ok(response)
	}

	
}

