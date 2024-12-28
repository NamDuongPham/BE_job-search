package com.example.movieba.model.response.news;


import jakarta.persistence.Column;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
public class NewsResponse {
    private Long idNew;
    private String titleNew;
    private String localName;
    private String describeNew;
    private String statusNew;
    private Date timeNews;
    private String skill;
    private Long wage;
    private String level;
    private Long countCv;
    private String nameLocation;
    private String nameCareer;

}
