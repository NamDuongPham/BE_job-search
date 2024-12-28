package com.example.movieba.model.response.cv;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CvInNewResponse {
    private Long idCv;
    private String nameCv;
    private String nameCareer;
    private String nameLocation;
    private String status;
    private String content;
}
