package coe817.project;

import java.sql.*;

public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:users.db";

    public static void initDB() {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            String sql = """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    balance INTEGER DEFAULT 0
                );
                """;
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            System.out.println("DB Init Error: " + e.getMessage());
        }
    }

    public static boolean registerUser(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO users (username, password, balance) VALUES (?, ?, 0)")) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            return false; // likely already exists
        }
    }

    public static boolean verifyLogin(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?")) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    // NEW: Get user's balance
    public static int getBalance(String username) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT balance FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() ? rs.getInt("balance") : 0;
        } catch (SQLException e) {
            return 0;
        }
    }

    // NEW: Update balance directly
    public static boolean updateBalance(String username, int newBalance) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("UPDATE users SET balance = ? WHERE username = ?")) {
            pstmt.setInt(1, newBalance);
            pstmt.setString(2, username);
            return pstmt.executeUpdate() == 1;
        } catch (SQLException e) {
            return false;
        }
    }

    // NEW: Deposit wrapper
    public static boolean deposit(String username, int amount) {
        int current = getBalance(username);
        return updateBalance(username, current + amount);
    }

    // NEW: Withdraw wrapper
    public static boolean withdraw(String username, int amount) {
        int current = getBalance(username);
        if (current >= amount) {
            return updateBalance(username, current - amount);
        }
        return false;
    }
}
