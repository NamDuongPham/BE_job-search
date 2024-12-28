package com.example.movieba.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter

@Entity
public class Location {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idLocation;

    @Column
    private String nameLocation;

    @OneToMany(mappedBy = "location")
    private List<News> news = new ArrayList<>();

    @OneToMany(mappedBy = "locationCv")
    private List<Cv> cvList = new ArrayList<>();
}
