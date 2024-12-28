package com.example.movieba.mapper;


import com.example.movieba.entities.Company;
import com.example.movieba.entities.News;
import com.example.movieba.model.request.news.NewsRequest;
import com.example.movieba.model.response.company.CompanyResponse;
import com.example.movieba.model.response.news.NewsResponse;
import com.example.movieba.utils.BeanUtils;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class NewsMapper  implements Mapper{
    public News to(NewsRequest newsRequest){

        News news = new News();
        BeanUtils.refine(newsRequest,news,BeanUtils::copyNonNull);
        return news;
    }

    public NewsResponse from(News news){
        NewsResponse newsResponse = new NewsResponse();
        BeanUtils.refine(news,newsResponse,BeanUtils::copyNonNull);
        return newsResponse;
    }
}
