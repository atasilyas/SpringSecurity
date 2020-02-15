package rc.bootsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rc.bootsecurity.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUserName(String username);


}
