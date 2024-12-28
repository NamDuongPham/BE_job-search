package com.example.movieba.model.request.news;

import jakarta.persistence.Column;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class NewsRequest {
    private String titleNew;
    private String describeNew;
    private String localName;
    private String skill;
    private Long wage;
    private String level;
    private Long idLocation;
    private Long idCareer;
}
