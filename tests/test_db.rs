use db::Database;

#[test]
fn test_db_connection(){
	let db = Database::connect("memory", "test", "test");
}