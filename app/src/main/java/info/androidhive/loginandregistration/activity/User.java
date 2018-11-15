package info.androidhive.loginandregistration.activity;

public class User {
	String username;
    String password;
 public User(String usuario, String clave) {
     this.username = usuario;
     this.password = clave;
 }
 public String getPassword() {
	 return this.password;
 }
 public String getUsername() {
	 return this.username;
 }
}
