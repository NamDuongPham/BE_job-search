package com.example.movieba.controller.Auth;

import com.example.movieba.controller.BaseController;
import com.example.movieba.model.request.auth.AuthRequest;
import com.example.movieba.model.request.user.ResetPasswordRequest;
import com.example.movieba.model.request.user.UserInfoRequest;
import com.example.movieba.model.response.ApiResponse;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.repository.UserRepository;
import com.example.movieba.security.JwtService;
import com.example.movieba.service.UserService;
import com.example.movieba.utils.EmailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class AuthController extends BaseController {

    @Autowired
    private final UserService userService;

    @Autowired
    private final JwtService jwtService;
    @Autowired
    UserRepository userRepository;

    @Autowired
    EmailServiceImpl emailService;

    @Autowired
    private final AuthenticationManager authenticationManager;

    public AuthController(UserService userService, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<BaseResponse> register(@RequestBody UserInfoRequest userInfoRequest){
        return success( userService.createUser(userInfoRequest));
    }

    @PostMapping("/register-company")
    public ResponseEntity<BaseResponse> registerCompany(@RequestBody UserInfoRequest userInfoRequest){
        return success( userService.createCompany(userInfoRequest));
    }


    @PostMapping("/login")
    public ResponseEntity<BaseResponse> userLogin(@RequestBody AuthRequest authRequest){
//
//        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUserName(),authRequest.getPassword()));
//        var user = userRepository.findByUserName(authRequest.getUserName())
//            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//        if (authentication.isAuthenticated() & user.getStatus() == 0){
//            return success(jwtService.generateToken(authRequest.getUserName()));
//
//        }else{
//            return success("invalid user reuest!");
//
//        }
        try {
            // Xác thực người dùng
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword())
            );

            if (authentication.isAuthenticated()) {
                // Lấy thông tin người dùng từ repository
                var user = userRepository.findByUserName(authRequest.getUserName())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                // Kiểm tra status
                if (user.getStatus() == 0) {
                    // Nếu status = 0, tạo và trả về token
                    String token = jwtService.generateToken(authRequest.getUserName());
                    return success(token);
                } else {
                    // Nếu status != 0, trả về thông báo lỗi
                     return success();
                }
            } else {
                return success();
            }
        } catch (Exception e) {
            return success();
        }
    }
    @PostMapping("/reset")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest reset) {

        if(!userRepository.existsByEmail(reset.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email not exist"),
                    HttpStatus.BAD_REQUEST);
        }
        String message = userService.resetPassword(reset);
        emailService.sendSimpleEmail(reset.getEmail(), "MK",message);
        System.out.println(reset.getEmail());
        return new ResponseEntity(new ApiResponse(true, "ok!"),
                HttpStatus.OK);
    }
}
