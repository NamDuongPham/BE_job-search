package com.example.movieba.repository;

import com.example.movieba.entities.Role;
import com.example.movieba.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Set<Role> findByRoleIdIn(List<Long> ids);
}
