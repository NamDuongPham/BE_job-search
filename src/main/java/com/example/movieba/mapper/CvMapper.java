package com.example.movieba.mapper;


import com.example.movieba.entities.Cv;
import com.example.movieba.model.response.cv.CvResponse;
import com.example.movieba.utils.BeanUtils;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Component
public class CvMapper implements Mapper{
    public CvResponse from(Cv cv){
        CvResponse cvResponse = new CvResponse();
        BeanUtils.refine(cv,cvResponse,BeanUtils::copyNonNull);
        return cvResponse;
    }
}
