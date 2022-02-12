package com.martin.webshop.DAO;

import com.martin.webshop.models.User;
import com.martin.webshop.payload.request.SignupRequest;
import com.martin.webshop.repository.UserRepository;
import com.martin.webshop.security.jwt.AuthTokenFilter;
import com.martin.webshop.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserDAO {
    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthTokenFilter authTokenFilter;

    @Autowired
    UserRepository userRepository;

    public User getUserByJwt(String jwt) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);
        User user = userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("User Not Found with username: " + username));
        return user;
    }

    public void saveUser(User user){
        userRepository.save(user);
    }

    public Boolean usernameAlreadyExists(SignupRequest signUpRequest){
        if(userRepository.existsByUsername(signUpRequest.getUsername())){
           return true;
        }
        return false;
    }

    public Boolean emailAlreadyExists(SignupRequest signUpRequest){
        if(userRepository.existsByEmail(signUpRequest.getEmail())){
            return true;
        }
        return false;
    }
}
