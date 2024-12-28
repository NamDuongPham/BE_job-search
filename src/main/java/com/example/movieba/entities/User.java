package com.example.movieba.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;


import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Setter
@Getter


@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column
    private String userName;

    @Column
    private String password;

    @Column
    private String email;

    @Column
    private String avatar;

    @Column
    private String address;

    @Column
    private String fullName;

    @Column
    private int status;

    @Column
    private String cvs;

    @Column
    private String jobFavourite;

    @Column(columnDefinition = "BIGINT default 0")
    private Long total;

    @Column
    private String applyNews;

    @OneToOne(mappedBy = "user")
    private UserService userService;


    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "permission", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "userId"),
    inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "roleId"))

    @JsonIgnore
    private Set<Role> roles = new HashSet<>();

    @OneToOne(mappedBy = "user")
    private Company company;


}
