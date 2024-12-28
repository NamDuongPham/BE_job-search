package com.example.movieba.model.response.cv;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CvRequest {
    private String author;
    private String data;
    private Long careerId;
    private Long locationId;
}
