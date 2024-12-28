package com.example.movieba.repository;

import com.example.movieba.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long>, JpaSpecificationExecutor<User> {
    Optional<User> findByUserNameOrEmail(String userName, String email);

    Optional<User> findByUserName(String userName);
    Boolean existsByEmail(String email);
}
