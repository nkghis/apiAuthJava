package nkagou.ci.api.repository;

import nkagou.ci.api.models.ERole;
import nkagou.ci.api.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}
