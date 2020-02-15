package rc.bootsecurity.repository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rc.bootsecurity.model.User;

import java.util.Arrays;
import java.util.List;


@Service
public class DbInit implements CommandLineRunner{

    private PasswordEncoder passwordEncoder;
    private UserRepository  userRepository;

    public DbInit(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {

        //Delete All
        this.userRepository.deleteAll();

        // Create Users
        User dan = new User("dan",  passwordEncoder.encode("dan123"), "USER" , "");
        User manager = new User("manager", passwordEncoder.encode("manager123") , "MANAGER", "ACCESS_TEST1,ACCESS_TEST2,ACCESS_TEST3");
        User admin = new User("admin", passwordEncoder.encode("admin123"), "ADMIN", "ACCESS_TEST1");



        //Save User to db
        List<User> users =  Arrays.asList(dan,admin,manager);
        this.userRepository.saveAll(users);
    }
}
