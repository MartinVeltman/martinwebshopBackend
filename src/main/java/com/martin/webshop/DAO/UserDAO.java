package com.martin.webshop.DAO;

import com.martin.webshop.models.User;
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
}
