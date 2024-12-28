package com.example.movieba.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Setter
@Getter

@Entity
public class News {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idNew;
    @Column
    private String titleNew;
    @Column
    private String localName;
    @Column(columnDefinition = "text")
    private String describeNew;
    @Column
    private String statusNew;
    @Column
    private Date timeNews;
    @Column
    private String skill;
    @Column
    private String level;
    @Column(columnDefinition = "BIGINT default 0")
    private Long wage;

    @Column
    private String listCV;

    @ManyToOne
    @JoinColumn(name = "idLocation")
    private Location location;

    @ManyToOne
    @JoinColumn(name = "careerId")
    private Career career;
}
