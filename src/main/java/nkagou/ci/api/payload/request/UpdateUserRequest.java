package nkagou.ci.api.payload.request;

import javax.validation.constraints.*;

public class UpdateUserRequest {

    @NotBlank(message = "username, ne peut pas être vide")
    @Size(min = 3, max = 20, message = "username, la taille doit être comprise entre 3 et 20")
    private String username;

    /*@NotEmpty(message = "email, ne peut pas être vide")*/
    @Size(max = 50)
    @Email(message = "email, non syntaxiquement non correct")
    private String email;

    /*@NotNull(message = "password, ne peut pas être vide")*/
    private String fullname;



    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
