from fastapi import FastAPI, Depends
from routers.superadmin import router ,get_current_user


# Create the FastAPI app
app = FastAPI(title="ICGMS(Development)")

is_valid=[Depends(get_current_user)]
app.include_router(router, tags=["SUPERADMIN"])
# app.include_router(customer.router,prefix='/customer', tags=["Customer"],dependencies=is_valid)



