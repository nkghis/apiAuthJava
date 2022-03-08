package nkagou.ci.api.controllers;

import nkagou.ci.api.models.ERole;
import nkagou.ci.api.models.Role;
import nkagou.ci.api.models.User;
import nkagou.ci.api.payload.request.ChangePasswordRequest;
import nkagou.ci.api.payload.request.LoginRequest;
import nkagou.ci.api.payload.request.SignupRequest;
import nkagou.ci.api.payload.request.UpdateUserRequest;
import nkagou.ci.api.payload.response.JwtResponse;
import nkagou.ci.api.payload.response.MessageResponse;
import nkagou.ci.api.repository.RoleRepository;
import nkagou.ci.api.repository.UserRepository;
import nkagou.ci.api.security.jwt.JwtUtils;
import nkagou.ci.api.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return ResponseEntity.ok(new JwtResponse(jwt,

                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getFullname(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: Nom d'utilisateur déjà pris!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: cet email est déjà utilisé!"));
        }
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getFullname().toUpperCase());
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Erreur : le rôle est introuvable."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Erreur : le rôle est introuvable."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Erreur : le rôle est introuvable."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Erreur : le rôle est introuvable."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("Utilisateur enregistré avec succès"));
    }

    @PostMapping("/changepassword")
    public ResponseEntity<?> changeUserPassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest ){

        if (!userRepository.existsByUsername(changePasswordRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: Nom d'utilisateur introuvable!"));
        }
        Optional<User> u = userRepository.findByUsername(changePasswordRequest.getUsername());
        //User user = userRepository.findByUsername(changePasswordRequest.getUsername());

        User user = userRepository.getById(u.get().getId());
        //User user = userRepository.getById(u.get().getId());
        String password = encoder.encode(changePasswordRequest.getPassword());
        user.setPassword(password);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("Mot de passe modifié avec succès"));
    }

    /*
    * Update user information
    * email
    * fullname
    * */
    @PostMapping("/updateuser")
    public ResponseEntity<?>  updateUser(@Valid @RequestBody UpdateUserRequest updateUserRequest ){

        if (!userRepository.existsByUsername(updateUserRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: Nom d'utilisateur introuvable!"));
        }
        if (userRepository.existsByEmail(updateUserRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: cet email est déjà utilisé!"));
        }
        if (updateUserRequest.getFullname() == null && updateUserRequest.getEmail() == null ){
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Erreur: le champ 'fullname' ou 'email' est requis"));
        }

        Optional<User> u = userRepository.findByUsername(updateUserRequest.getUsername());

        User user = userRepository.getById(u.get().getId());
        //User user = userRepository.findByUsername(UpdateUserRequest.getUsername());

        if (updateUserRequest.getEmail() == null)
        {
            user.setFullname(updateUserRequest.getFullname().toUpperCase());
            userRepository.save(user);
        }

        if (updateUserRequest.getFullname() == null){
            user.setEmail(updateUserRequest.getEmail());
            userRepository.save(user);
        }
        if (updateUserRequest.getFullname() != null && updateUserRequest.getEmail() != null ){
            user.setEmail(updateUserRequest.getEmail());
            user.setFullname(updateUserRequest.getFullname().toUpperCase());
            userRepository.save(user);
        }


        return ResponseEntity.ok(new MessageResponse("Utilisateur modifié avec succès"));
    }
}
