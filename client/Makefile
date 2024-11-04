NAME = Ben_AFK

#########
RM = rm -rf
CC = c++
CFLAGS = -Werror -Wextra -Wall -Os $(shell pkg-config --cflags Qt5Widgets Qt5Network)
LDFLAGS = $(shell pkg-config --libs Qt5Widgets Qt5Network)
RELEASE_CFLAGS = $(CFLAGS) -DNDEBUG

#########

#########
FILES = main Ben_AFK

SRC_DIR = srcs
OBJ_DIR = objs
MOC_DIR = moc
SRC = $(addprefix $(SRC_DIR)/, $(addsuffix .cpp, $(FILES)))
OBJ = $(addprefix $(OBJ_DIR)/, $(FILES:=.o))
MOC_HEADERS = $(SRC_DIR)/Ben_AFK.h
MOC_CPP = $(MOC_DIR)/Ben_AFK.moc.cpp
MOC_OBJ = $(OBJ_DIR)/Ben_AFK.moc.o
DEP = $(OBJ:.o=.d)
#########

#########
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CC) -MMD $(CFLAGS) -I$(SRC_DIR) -fPIC -c $< -o $@

$(MOC_OBJ): $(MOC_CPP)
	@mkdir -p $(@D)
	$(CC) -MMD $(CFLAGS) -I$(SRC_DIR) -fPIC -c $< -o $@

$(MOC_CPP): $(MOC_HEADERS)
	@mkdir -p $(MOC_DIR)
	moc $< -o $@

all: $(NAME)

$(NAME): $(OBJ) $(MOC_OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(MOC_OBJ) -o $(NAME) $(LDFLAGS)
	@echo "BUILD SUCCESSFUL"

release: CFLAGS = $(RELEASE_CFLAGS)
release: re
	@echo "RELEASE BUILD DONE"

clean:
	$(RM) $(OBJ) $(DEP) $(MOC_CPP) $(MOC_OBJ)
	$(RM) -r $(OBJ_DIR) $(MOC_DIR)
	@echo "OBJECTS AND MOC FILES REMOVED"

fclean: clean
	$(RM) $(NAME)
	@echo "EVERYTHING REMOVED"

re: fclean all

.PHONY: all clean fclean re release

-include $(DEP)
