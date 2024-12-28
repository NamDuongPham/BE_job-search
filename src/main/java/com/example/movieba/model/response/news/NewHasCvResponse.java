package com.example.movieba.model.response.news;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class NewHasCvResponse {
    private String nameNews;
    private String nameCv;
    private String status;
    private String content;
}
