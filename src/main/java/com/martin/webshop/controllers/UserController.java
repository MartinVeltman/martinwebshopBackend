package com.martin.webshop.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import com.alibaba.fastjson.JSONObject;
import com.github.lambdaexpression.annotation.EnableRequestBodyParam;
import com.github.lambdaexpression.annotation.RequestBodyParam;
import com.google.api.client.json.Json;
import com.martin.webshop.models.ERole;
import com.martin.webshop.models.Role;
import com.martin.webshop.models.User;
import com.martin.webshop.payload.response.JwtResponse;
import com.martin.webshop.repository.RoleRepository;
import com.martin.webshop.repository.UserRepository;
import com.martin.webshop.security.jwt.AuthTokenFilter;
import com.martin.webshop.security.services.UserDetailsServiceImpl;
import com.martin.webshop.security.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.*;

import com.martin.webshop.payload.request.LoginRequest;
import com.martin.webshop.payload.request.SignupRequest;
import com.martin.webshop.payload.response.MessageResponse;
import com.martin.webshop.security.jwt.JwtUtils;
import com.martin.webshop.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@EnableRequestBodyParam
@RequestMapping("/api/v1")
public class UserController {
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

    @Autowired
    AuthTokenFilter authTokenFilter;

    @Autowired
    UserService userService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @PatchMapping("/user/changePassword")
    public ResponseEntity<?> changePassword(HttpServletRequest request, @RequestBodyParam String newPassword) {
        try {
            String jwt = authTokenFilter.parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                User user = userService.getUserByToken(jwt);
                userService.changePassword(user, newPassword);
                return MessageResponse.generateResponse("Nieuw wachtwoord opgeslagen", HttpStatus.OK, null);
            }
        } catch (Exception e) {
            logger.error("Geen gebruikersnaam gevonden", e);
        }
        return MessageResponse.generateResponse("Nieuw wachtwoord opslaan mislukt", HttpStatus.BAD_REQUEST, null);

    }

    @PatchMapping("/user/createOrder")
    public ResponseEntity<?> createOrder(HttpServletRequest request, @RequestBodyParam String orderValue) {
        try {
            String jwt = authTokenFilter.parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                User user = userService.getUserByToken(jwt);
                userService.createOrder(user, orderValue);
                return MessageResponse.generateResponse("Order aangemaakt", HttpStatus.OK, null);
            }
        } catch (Exception e) {
            logger.error("Order aanmaken mislukt", e);
        }
        return MessageResponse.generateResponse("Order aanmaken mislukt", HttpStatus.BAD_REQUEST, null);

    }

    @GetMapping("/user/getOrderValue")
    public Object getOrderValue(HttpServletRequest request) {
        try {
            String jwt = authTokenFilter.parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                User user = userService.getUserByToken(jwt);
                return userService.getMoneySpend(user);
            }
        } catch (Exception e) {
            logger.error("Geen gebruikersnaam gevonden", e);
        }
        return MessageResponse.generateResponse("Er is iets fout gegaan bij het opvragen van je ordervalue",
                HttpStatus.BAD_REQUEST, null);

    }

    @PostMapping("/user/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        return ResponseEntity.ok(new JwtResponse(jwt));

    }

    @PostMapping("/user/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userService.usernameAlreadyExists(signUpRequest)) {
            return ResponseEntity
                    .badRequest()
                    .body(MessageResponse.generateResponse("Error: Username is already taken!",
                            HttpStatus.BAD_REQUEST, null));
        }
        //checkt op user of die al bestaat
        if (userService.emailAlreadyExists(signUpRequest)) {
            return ResponseEntity
                    .badRequest()
                    .body(MessageResponse.generateResponse("Error: Email is already in use!",
                            HttpStatus.BAD_REQUEST, null));
        }

        // Creeert nieuwe user
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        user.setMoneySpend(0);

        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(userRole);

        user.setRoles(roles);
        userService.saveUser(user);
        return MessageResponse.generateResponse("Account succesvol aangemaakt", HttpStatus.OK, null);
    }


}
