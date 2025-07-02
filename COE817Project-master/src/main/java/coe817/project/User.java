package coe817.project;

public class User {
    
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;                     // same object
        if (obj == null || getClass() != obj.getClass()) return false; // null or different class
        User user = (User) obj;                           // cast
        return (this.username.equals(user.username) && this.password.equals(user.password));   // compare fields
    }
}
