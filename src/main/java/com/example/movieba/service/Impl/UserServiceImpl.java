package com.example.movieba.service.Impl;

import com.example.movieba.entities.*;
import com.example.movieba.exception.BusinessCode;
import com.example.movieba.exception.BusinessException;
import com.example.movieba.mapper.UserMapper;
import com.example.movieba.model.request.user.PasswordRequest;
import com.example.movieba.model.request.user.ProfileRequest;
import com.example.movieba.model.request.user.ResetPasswordRequest;
import com.example.movieba.model.request.user.UserInfoRequest;
import com.example.movieba.model.response.UserInfoResponse;
import com.example.movieba.model.response.user.RoleUserResponse;
import com.example.movieba.repository.*;
import com.example.movieba.security.JwtService;
import com.example.movieba.service.FileStorageService;
import com.example.movieba.service.UserService;
import com.example.movieba.utils.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final CompanyRepository companyRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    private final NewsRepository newsRepository;
    private final CvRepository cvRepository;

    private final FileStorageService fileStorageService;
    private final UserMapper userMapper;

    private final RoleRepository roleRepository;

    private final JwtService jwtService;

    @Override
    public String createUser(UserInfoRequest infoRequest) {
        String message = "";
        Optional<User> userCheck = userRepository.findByUserNameOrEmail(infoRequest.getUserName(), infoRequest.getEmail());
        if (userCheck.isEmpty()) {
            User user = userMapper.to(infoRequest);
            Set<Role> roles = roleRepository.findByRoleIdIn(Arrays.asList(1L));
            user.setRoles(roles);
            user.setTotal(0L);
            userRepository.save(user);
            message = "CREATE-SUCCESS";
        } else {
            message = "CREATE-FAIL";
        }
        return message;
    }

    @Override
    public String createCompany(UserInfoRequest infoRequest) {
        String message = "";
        Optional<User> userCheck = userRepository.findByUserNameOrEmail(infoRequest.getUserName(), infoRequest.getEmail());
        if (userCheck.isEmpty()) {
            User user = userMapper.to(infoRequest);
            Set<Role> roles = roleRepository.findByRoleIdIn(Arrays.asList(3L));
            user.setRoles(roles);
            userRepository.save(user);

            Company company = new Company();
            company.setUser(user);
            companyRepository.save(company);

            message = "CREATE-SUCCESS";
        } else {
            message = "CREATE-FAIL";
        }
        return message;
    }

    @Override
    public UserInfoResponse infoUser(HttpServletRequest request) {
        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        return userMapper.from(user.get());
    }

    @Override
    public UserInfoResponse infoById(long id) {
        Optional<User> findUser = userRepository.findById(id);
        findUser.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));
        if (findUser.get() != null) {
            return userMapper.from(findUser.get());
        }
        return null;
    }

    @Override
    public String updatePassword(HttpServletRequest request, PasswordRequest passwordRequest) {
        String message = "";

        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        if (passwordRequest.getNewPassword().equalsIgnoreCase(passwordRequest.getNewPasswordT())) {
            User userUpdate = user.get();
            userUpdate.setPassword(passwordEncoder.encode(passwordRequest.getNewPassword()));
            userRepository.save(userUpdate);
            message = "PASSWORD-SUCCESS";
        } else {
            message = "NOT-EQUAL";
        }

        return message;
    }

    @Override
    public UserInfoResponse updateProfile(HttpServletRequest request, ProfileRequest profileRequest) {
        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        if (user.get() != null) {
            User userUpdate = user.get();
            userUpdate.setAddress(profileRequest.getAddress());
            userUpdate.setFullName(profileRequest.getFullName());
            userRepository.save(userUpdate);
            return userMapper.from(userUpdate);
        }
        return userMapper.from(user.get());
    }

    @Override
    public List<String> roleUser(HttpServletRequest request) {
        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        List<String> findRole = user.get().getRoles().stream().map(t -> t.getRoleName()).collect(Collectors.toList());
        return findRole;

    }

    @Override
    public Page<UserInfoResponse> getAll(Pageable pageable) {
        Page<User> users = userRepository.findAll(pageable.previousOrFirst());
        return users.map(userMapper::from);
    }

    @Override
    public List<UserInfoResponse> getUsers() {
        List<User> users = userRepository.findAll();
        return users.stream().map(t -> {
            UserInfoResponse userInfoResponse = userMapper.from(t);
            return userInfoResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public int getTotalUser() {
        return userRepository.findAll().size();
    }

    @Override
    public void addCompany(long id, long role) {
        Optional<User> user = userRepository.findById(id);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));
        Set<Role> roles = roleRepository.findByRoleIdIn(Arrays.asList(role));


        if (user.get() != null && user.get().getCompany() == null) {
            User userUpdate = user.get();
            userUpdate.setRoles(roles);
            userRepository.save(userUpdate);
            Company company = new Company();
            company.setUser(user.get());
            companyRepository.save(company);
        }
    }

    @Override
    public void changeStatusAccount(long id, long status) {
        Optional<User> user = userRepository.findById(id);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));
        if (user.get() != null) {
            User userUpdate = user.get();
            userUpdate.setStatus((int) status);
            userRepository.save(userUpdate);
        }
    }

    @Override
    public RoleUserResponse getRole(HttpServletRequest request) {
        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        RoleUserResponse response = new RoleUserResponse();
        response.setUserId(user.get().getUserId());
        response.setRoleName(user.get().getRoles().stream().map(Role::getRoleName).collect(Collectors.toList()).toString());

        if (user.get().getCompany() != null) {
            response.setComId(user.get().getCompany().getIdCompany());
        }


        return response;
    }

    @Override
    public UserInfoResponse updateImage(HttpServletRequest request, MultipartFile file) {
        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        if (user.get() != null) {
            User userUpdate = user.get();
            String url = fileStorageService.storeFile(file);
            userUpdate.setAvatar(url);
            userRepository.save(userUpdate);
            return userMapper.from(userUpdate);
        }
        return userMapper.from(user.get());
    }

    @Override
    public List<Cv> getCvs(long userId) {

        Optional<User> getUser = userRepository.findById(userId);
        if (getUser.get() != null && !getUser.get().getCvs().isBlank()) {
            List<Long> idCvs = Arrays.stream(getUser.get().getCvs().split(",")).map(t -> Long.parseLong(t)).collect(Collectors.toList());
            List<Cv> listCvs = cvRepository.findAllById(idCvs);
            return listCvs.stream().map(t -> {
                Cv cv = new Cv();
                cv.setIdCv(t.getIdCv());
                cv.setNameFile(t.getNameFile());
                cv.setCreateTime(t.getCreateTime());
                cv.setPathFile(t.getPathFile());
                cv.setSecurity(t.getSecurity());
                return cv;
            }).collect(Collectors.toList());
        }

        return null;
    }

    @Override
    public List<News> getJobFavorite(long userId) {
        Optional<User> findUser = userRepository.findById(userId);
        if (findUser.get() != null) {
            try {
                List<Long> idNews = Arrays.stream(findUser.get().getJobFavourite().split(",")).map(t -> Long.parseLong(t)).collect(Collectors.toList());
                return newsRepository.findAllByIdNewIsIn(idNews).stream().map(t->{
                    News news = new News();
                    news.setSkill(t.getSkill());
                    news.setLocalName(t.getLocalName());
                    news.setIdNew(t.getIdNew());
                    news.setDescribeNew(t.getDescribeNew());
                    news.setStatusNew(t.getStatusNew());
                    news.setTimeNews(t.getTimeNews());
                    news.setLevel(t.getLevel());
                    news.setTitleNew(t.getTitleNew());
                    news.setWage(t.getWage());

                    return news;
                }).collect(Collectors.toList());
            }catch (Exception ex){

            }

        }
        return null;
    }

    @Override
    public void addNewFavourite(long userId, long newId) {
        Optional<User> findUser = userRepository.findById(userId);

        if (findUser.get() != null) {
            User user = findUser.get();
            String list = "";
            if (findUser.get().getJobFavourite() != null) {
                list += findUser.get().getJobFavourite() + newId + ",";
            } else {
                list += newId + ",";
            }
            user.setJobFavourite(list);
            userRepository.save(user);
        }
    }
    @Override
    public String resetPassword(ResetPasswordRequest resetPasswordRequest) {

        String message = "";
        Optional<User> findUser = userRepository.findByUserNameOrEmail(resetPasswordRequest.getUserName(),resetPasswordRequest.getEmail());
        User user = findUser.get();
        int code = (int) Math.floor(((Math.random() * 899999) + 100000));
//        int code = 123456;
        String resetPassword = String.valueOf(code);

        user.setPassword(passwordEncoder.encode(resetPassword));
        userRepository.save(user);
        System.out.println(code);
        return  resetPassword;
    }
}
