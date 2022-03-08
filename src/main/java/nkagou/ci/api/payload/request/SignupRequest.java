package nkagou.ci.api.payload.request;

import java.util.Set;

import javax.validation.constraints.*;

public class SignupRequest {

    /*@NotNull(message = "le username ne peut pas être null ")*/
    /*@NotEmpty(message = "le username ne peut pas être vide")*/
    @NotBlank(message = "username, ne peut pas être vide")
    @Size(min = 3, max = 20, message = "username, la taille doit être comprise entre 3 et 20")
    private String username;

    @NotBlank(message = "email, ne peut pas être vide")
    @Size(max = 50)
    @Email(message = "email, non syntaxiquement non correct")
    private String email;

    @NotBlank(message = "fullname, ne peut pas être vide")
    @Size(max = 120)
    private String fullname;

    private Set<String> role;

    @NotBlank(message = "password, ne peut pas être vide")
    @Size(min = 6, max = 40, message = "password, la taille doit être comprise entre 6 et 40")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRole() {
        return this.role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }
}
