package com.example.movieba.mapper;

import com.example.movieba.entities.Company;
import com.example.movieba.entities.User;
import com.example.movieba.model.request.company.CompanyRequest;
import com.example.movieba.model.response.UserInfoResponse;
import com.example.movieba.model.response.company.CompanyResponse;
import com.example.movieba.utils.BeanUtils;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CompanyMapper implements Mapper {
    public Company to(CompanyRequest companyRequest){

        Company company = new Company();
        BeanUtils.refine(companyRequest,company,BeanUtils::copyNonNull);
        return company;
    }

    public CompanyResponse from(Company company){
        CompanyResponse companyResponse = new CompanyResponse();
        BeanUtils.refine(company,companyResponse,BeanUtils::copyNonNull);
        return companyResponse;
    }
}
