package com.martin.webshop.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.martin.webshop.models.ERole;
import com.martin.webshop.models.Item;
import com.martin.webshop.models.Role;
import com.martin.webshop.models.User;
import com.martin.webshop.payload.response.JwtResponse;
import com.martin.webshop.repository.ItemRepository;
import com.martin.webshop.repository.RoleRepository;
import com.martin.webshop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.martin.webshop.payload.request.LoginRequest;
import com.martin.webshop.payload.request.SignupRequest;
import com.martin.webshop.payload.response.MessageResponse;
import com.martin.webshop.security.jwt.JwtUtils;
import com.martin.webshop.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1")
public class RequestController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    ItemRepository itemRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

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


        return ResponseEntity.ok(new JwtResponse(jwt
//                , userDetails.getId(),
//                userDetails.getUsername(),
//                userDetails.getEmail(),
//                roles
        ));

//		return ResponseEntity.ok(jwt
//				,userDetails.getId(),
//				userDetails.getUsername(),
//				userDetails.getEmail(),
//				roles
//		));
    }

    @PostMapping("/user/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(MessageResponse.generateResponse("Error: Username is already taken!",
                            HttpStatus.BAD_REQUEST, null));
        }
        //checkt op user
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
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
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return MessageResponse.generateResponse("Account succesvol aangemaakt", HttpStatus.OK, null);
    }

    @PostMapping("/admin/createItem")
    public ResponseEntity<?> createItem(@RequestBody Item item) {
        itemRepository.save(item);
        return MessageResponse.generateResponse("Item succesvol toegevoegd", HttpStatus.OK, null);

    }

    @GetMapping("/user/getItems")
    @ResponseBody
    public Object getUsers() {
        try {
            List<Item> items = this.itemRepository.findAll();
            return items;
        } catch (Exception e) {
            return MessageResponse.generateResponse("An error has occurred: " + e, HttpStatus.BAD_REQUEST, null);
        }
    }

    @PatchMapping("/user/createOrder")
    public ResponseEntity<?> createItem(@RequestParam String username, Float orderValue){
        User user = userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("User Not Found with username: " + username));
        user.setMoneySpend(user.getMoneySpend() + orderValue);
        userRepository.save(user);

        return MessageResponse.generateResponse("Order geplaatst", HttpStatus.OK, null);
    }




}
