package in.springbootproject.expensetrackerapp.security;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import in.springbootproject.expensetrackerapp.entity.User;
import in.springbootproject.expensetrackerapp.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService{
    
        @Autowired
        private UserRepository userRepository;

        @Override
        public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

            User existingUser = userRepository.findByEmail(email).orElseThrow(() -> 
                            new UsernameNotFoundException("User not found for the email: "+email));
            
            
            return new org.springframework.security.core.userdetails.User(existingUser.getEmail(),
                                                    existingUser.getPassword(),new ArrayList<>());

            
            
            
                            
        }
    
}
