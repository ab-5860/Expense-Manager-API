package in.springbootproject.expensetrackerapp.service;

import in.springbootproject.expensetrackerapp.entity.User;
import in.springbootproject.expensetrackerapp.entity.UserModel;

public interface UserService {
    
        User createUser(UserModel user);

        User readUser();

        User updateUser(UserModel user);

        void deleteUser();

        User getLoggedInUser();
}
