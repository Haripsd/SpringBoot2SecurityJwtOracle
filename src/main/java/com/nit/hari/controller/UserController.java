package com.nit.hari.controller;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nit.hari.model.User;
import com.nit.hari.model.UserRequest;
import com.nit.hari.model.UserResponse;
import com.nit.hari.service.IUserService;
import com.nit.hari.serviceImpl.UserServiceImpl;
import com.nit.hari.util.JwtUtil;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/user")
public class UserController {
	
	private Logger log = LoggerFactory.getLogger(UserController.class);
	
	@Autowired
	private IUserService userService;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	AuthenticationManager authenticationManager;

	// 1. Save User
	@PostMapping("/saveUser")
	public ResponseEntity<String> saveUser(@RequestBody User user){
		Integer id = userService.saveUser(user);
		
		return new ResponseEntity<String>("Saved '"+id+"' User ",HttpStatus.OK);
	}
	
	
	// 2. Validate User and Generate Token
	@PostMapping("/login")
	public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request){
		System.out.println("request : "+request);
		//  Validate User with DataBase
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getUsername(), request.getPassword()));
		
		String token = jwtUtil.generateToken(request.getUsername());
		
		return ResponseEntity.ok(new UserResponse(token,
				"Success! Generated By HariPrasad"));
	}
	
	// 3. after login Access Data
	@PostMapping("/welcome")
	public ResponseEntity<String> accessData(Principal p){
		log.info("Login User : "+p.getName());
		return new ResponseEntity("Hello User",HttpStatus.OK);
	}
}
