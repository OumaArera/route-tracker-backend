print("Hello, World!")


{
    "shelf_space":{
        "text": True,  
        "image": False
    },
    "stock_level":{
        "text":True,
        "image": True
    },
    "competitors_branding":{
        "text":True,
        "image": True
    },
    "competitors_sales":{
        "text":True,
        "image": True
    },
    "sales_orders_return":{
        "text":True,
        "image": False
    },
    "price_variations":{
        "text":True,
        "image": False
    },
    

}

# {
#     "pricing_labeling":{
#         "text": "some text",
#         "image": None
#     },
#     "shelf_space":{
#         "text": "some text",
#         "image": "an image address"
#     },
#     "competitors_branding":{
#         "text": "some text",
#         "image": None
#     }

# }


# {
#     "pricing_labeling":80,
#     "shelf_space":95,
#     "stock_level": 90,
#     "competitors_branding":46,
#     "completeness": 60,
#     "clarity": 90,
#     "detail": 70,
#     "timely": 100,

# }



# {
#             "manager_id": "userId",
#             "staff_no": "selectedMerchandiser",
#             "status": "pending",
#             "date_range": {
#                 "start_date": "dateRange.startDate",
#                 "end_date": "dateRange.endDate",
#             },
#             "instructions": [
#                 {
#                     "manager_id": "userId",
#                     "staff_no": "selectedMerchandiser",
#                     "status": "pending",  # pending or complete. This is the status to check
#                     "date_range": {
#                         "start_date": "dateRange.startDate",
#                         "end_date": "dateRange.endDate",
#                     },
#                     "instructions": "instructionSets",
#                 },
#                 {
#                     "manager_id": "userId",
#                     "staff_no": "selectedMerchandiser",
#                     "status": "pending",  # pending or complete. This is the status to check
#                     "date_range": {
#                         "start_date": "dateRange.startDate",
#                         "end_date": "dateRange.endDate",
#                     },
#                     "instructions": "instructionSets",
#                 }
#             ] # An array of each instruction
#         }


{
    "January, 2024":{
        "total_perormance":80
        
    },
    "February, 2024":{
        "total_perormance":71
        
    },
    "March, 2024":{
        "total_perormance": 94
        
    },
    "April, 2024":{
        "total_perormance":70
        
    }
    # Till December
}

{
    "Shelf Space": {
        "text": "text response",
        "image": "image"
    },
    "Competitors Branding Strategies": {
        "text": "text response",
        "image": None
    }

    # And more and more
}

{
    "date_time": "Wed, 19 Jun 2024 19:52:04 GMT",
    "id": 3,
    "manager_id": 11,
    "merchandiser": "Judy Achieng",
    "response": {
        "Competitors Branding Strategies": {
            "image": "2024-06-19_17-34.png",
            "text": "Test"
        },
        "Shelf Space": {
            "image": "2024-06-19_17-34.png",
            "text": "Test"
        },
        "Price and Labeling":{
            "image": "2024-06-19_17-34.png",
            "text": "Test"
        }
    },
    "status": "pending"
}



{
    "sector_name": "Consumer Packaging Goods",
    "company_name": "Mash Industries Limited",
    "admin_id": 29,
    "performance_metric": {
        "shelf_space":{
            "text": True,  
            "image": False
        },
        "stock_level":{
            "text":True,
            "image": True
        },
        "competitors_branding":{
            "text":True,
            "image": True
        },
        "competitors_sales":{
            "text":True,
            "image": True
        },
        "sales_orders_return":{
            "text":True,
            "image": False
        },
        "price_variations":{
            "text":True,
            "image": False
        }

    }
}

{
    "name": f"fist_name last_name",
    "score": "", #The average of total_performance
    "month": "" # current month
}

# data = request.get_json()
# route_plan_id = data.get("route_plan_id")
# instruction_id = data.get("instruction_id")
# manager_id = data.get("manager_id")
# merchandiser_id = data.get("merchandiser_id")
# message = data.get("message")

{
    "route_plan_id": int,
    "instruction_id": int,
    "manager_id": int,
    "merchandiser_id": int,
    "message": "The message entered in the text area"
}



# message_id = data.get("message_id")
# reply_text = data.get("reply")
# sender = data.get("sender")

# {
#     "message_id": "", # ID of the message he is replying to
#     "reply": "",  # The content of what user entered in the textarea. It is required
#     "sender": ""  # The role
# }
