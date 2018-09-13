from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///categorywithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

category2 = Category(user_id=2, name="Soccer")
session.add(category2)
session.commit()

menuItem1 = Item(user_id=2, name="Stick", description="Random Stick description", category=category2)

session.add(menuItem1)
session.commit


category3 = Category(user_id=3, name="Basket Ball")
session.add(category3)
session.commit()

menuItem1 = Item(user_id=3, name="Basket Ball", description="Random BB BAll description", category=category3)

session.add(menuItem1)
session.commit


category4 = Category(user_id=4, name="Base Ball")
session.add(category4)
session.commit()

menuItem1 = Item(user_id=4, name="Bat", description="Random Bat description", category=category4)

session.add(menuItem1)
session.commit


category5 = Category(user_id=5, name="Frisbee")
session.add(category5)
session.commit()

menuItem1 = Item(user_id=5, name="throw disc", description="Random disc description", category=category5)

session.add(menuItem1)
session.commit


category6 = Category(user_id=6, name="Foosball")
session.add(category6)
session.commit()

menuItem1 = Item(user_id=6, name="Table", description="Random Table description", category=category6)

session.add(menuItem1)
session.commit


category7 = Category(user_id=7, name="Skating")
session.add(category7)
session.commit()

menuItem1 = Item(user_id=7, name="Shoes", description="Random Shoe description", category=category7)

session.add(menuItem1)
session.commit



print "added menu items!"
