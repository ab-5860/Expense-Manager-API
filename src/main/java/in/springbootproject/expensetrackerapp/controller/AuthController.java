package in.springbootproject.expensetrackerapp.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import in.springbootproject.expensetrackerapp.entity.AuthModel;
import in.springbootproject.expensetrackerapp.entity.JwtResponse;
import in.springbootproject.expensetrackerapp.entity.User;
import in.springbootproject.expensetrackerapp.entity.UserModel;
import in.springbootproject.expensetrackerapp.security.CustomUserDetailsService;
import in.springbootproject.expensetrackerapp.service.UserService;
import in.springbootproject.expensetrackerapp.util.JwtTokenUtil;

@RestController
public class AuthController {
    

    
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody AuthModel authModel) throws Exception
    {
        
        authenticate(authModel.getEmail(), authModel.getPassword());

        //need to generate the jwt token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authModel.getEmail());

        final String token = jwtTokenUtil.generateToken(userDetails);
        return new ResponseEntity<JwtResponse>(new JwtResponse(token),HttpStatus.OK);
    }

    private void authenticate(String email, String password) throws Exception{

        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e) {
            throw new Exception("User disabled");
        }catch(BadCredentialsException e)
        {
            throw new Exception("Bad Credential");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<User> save(@Valid @RequestBody UserModel user)
    {
        return new ResponseEntity<User>(userService.createUser(user),HttpStatus.CREATED);
    }
}
