package re.mkw.srejaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A JAAS {@link LoginModule} authenticates users against a Ghidra Panel installation, given a
 * username and password.
 *
 * <p>Uses Argon2id for password hashing.
 *
 * <p>For further information see <a href="https://github.com/mkw-re/ghidra-panel">Ghidra Panel
 * repo</a>.
 */
public class PanelLoginModule implements LoginModule {

  private static final String USER_PROMPT_OPTION_NAME = "USER_PROMPT";
  private static final String PASSWORD_PROMPT_OPTION_NAME = "PASSWORD_PROMPT";

  private static final String JDBC_OPTION_NAME = "JDBC";

  private Subject subject;
  private CallbackHandler callbackHandler;
  private Map<String, Object> options;
  private String username;
  private char[] password;
  private Connection dbConn;

  private byte[] pwSalt;
  private byte[] pwHash;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    this.subject = subject;
    this.callbackHandler = callbackHandler;
    this.options = (Map<String, Object>) options;
  }

  @Override
  public boolean login() throws LoginException {
    connectToDatabase();
    getNameAndPassword();
    getPasswordHash();
    verifyPassword();
    return true;
  }

  @Override
  public boolean commit() throws LoginException {
    return false;
  }

  @Override
  public boolean abort() throws LoginException {
    return false;
  }

  @Override
  public boolean logout() throws LoginException {
    return false;
  }

  /**
   * Acquires a JDBC connection handle to the URI in options.
   *
   * @throws LoginException Failed to connect to database.
   */
  private void connectToDatabase() throws LoginException {
    String jdbc = options.getOrDefault(JDBC_OPTION_NAME, "").toString();
    if (jdbc.isEmpty()) {
      throw new LoginException("JDBC connection string not provided");
    }
    try {
      this.dbConn = DriverManager.getConnection(jdbc);
    } catch (SQLException e) {
      throw new LoginException("Failed to connect to database: " + e.getMessage());
    }
  }

  /**
   * Uses JAAS callback API to retrieve username and password from client.
   *
   * @throws LoginException Failed to retrieve username/password
   */
  private void getNameAndPassword() throws LoginException {
    String userPrompt = options.getOrDefault(USER_PROMPT_OPTION_NAME, "User name").toString();
    String passPrompt = options.getOrDefault(PASSWORD_PROMPT_OPTION_NAME, "Password").toString();

    List<Callback> callbacks = new ArrayList<>();
    NameCallback ncb = null;
    PasswordCallback pcb = null;

    if (username == null) {
      ncb = new NameCallback(userPrompt);
      callbacks.add(ncb);
    }
    if (password == null) {
      pcb = new PasswordCallback(passPrompt, false);
      callbacks.add(pcb);
    }

    if (!callbacks.isEmpty()) {
      try {
        callbackHandler.handle(callbacks.toArray(new Callback[0]));
        if (ncb != null) {
          username = ncb.getName();
        }
        if (pcb != null) {
          password = pcb.getPassword();
          pcb.clearPassword();
        }

        if (username == null || password == null) {
          throw new LoginException("Failed to get username or password");
        }
      } catch (Exception e) {
        throw new LoginException("Error during callback: " + e.getMessage());
      }
    }
    validateUsernameAndPasswordFormat();
  }

  /**
   * Validates whether user and pass provided by client don't contain invalid characters.
   *
   * @throws LoginException Invalid characters detected
   */
  private void validateUsernameAndPasswordFormat() throws LoginException {
    if (username.isEmpty() || password.length == 0) {
      throw new LoginException("Username or password is empty");
    }
    if (username.contains("\n") || username.contains("\0")) {
      throw new LoginException("Bad characters in username");
    }
    String tmpPass = String.valueOf(password);
    if (tmpPass.contains("\n") || tmpPass.contains("\0")) {
      throw new LoginException("Bad characters in password");
    }
  }

  /**
   * Retrieves the password hash and salt from the database.
   *
   * @throws LoginException Database error, username doesn't exist, or user didn't set password yet.
   */
  private void getPasswordHash() throws LoginException {
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = this.dbConn.prepareStatement("SELECT salt, hash FROM password WHERE username = ?");
      stmt.setString(1, this.username);

      rs = stmt.executeQuery();
      if (!rs.next()) {
        // TODO make URL configurable
        throw new LoginException("Please set your password at https:/panel.mkw.re");
      }

      this.pwSalt = rs.getBytes(1);
      this.pwHash = rs.getBytes(2);
    } catch (SQLException e) {
      throw new LoginException("Failed to prepare statement: " + e.getMessage());
    } finally {
      if (stmt != null) {
        try {
          stmt.close();
        } catch (SQLException ignored) {
        }
      }
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException ignored) {
        }
      }
    }
  }

  /**
   * Verifies that given password matches hash.
   *
   * @throws LoginException Wrong password
   */
  private void verifyPassword() throws LoginException {
    throw new LoginException("TODO!");
  }
}
