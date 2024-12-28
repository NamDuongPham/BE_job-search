package com.example.movieba.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
@Entity
public class Career {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long careerId;

    @Column
    private String nameCareer;

    @OneToMany(mappedBy = "career")
    List<News> newsList = new ArrayList<>();

    @OneToMany(mappedBy = "careerCv")
    List<Cv> cvList = new ArrayList<>();
}
