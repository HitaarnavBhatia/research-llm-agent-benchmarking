# Run #1 — langchain-ai/langchain

> Commit: `3dd0704e3835765e6f95f3f148f6c1739f18f9f4`  
> Timestamp: 2026-08-12 09:26:36 UTC  
> Part of master log: [all_outputs.md](./all_outputs.md)


════════════════════════════════════════════════════════════════════════
## Run #1 — langchain-ai/langchain @ `3dd0704e3835...`
════════════════════════════════════════════════════════════════════════

| Field | Value |
|---|---|
| **Run Number** | #1 |
| **Timestamp** | 2026-08-12 09:26:36 UTC |
| **Repository** | `langchain-ai/langchain` |
| **URL** | https://github.com/langchain-ai/langchain |
| **Commit Hash** | `3dd0704e3835765e6f95f3f148f6c1739f18f9f4` |
| **PyPI Package** | `langchain` |
| **Taint Output File** | `./pysa_result/pysa-runs_langchain-ai__langchain/taint-output.json` |
| **Individual File** | [run_001_langchain-ai_langchain_3dd0704e.md](./run_001_langchain-ai_langchain_3dd0704e.md) |

────────────────────────────────────────────────────────────────────────
### All Pysa Findings (Complete Callable List)

```
1. langchain.agents.agent.Agent.aplan
     2. langchain.agents.agent.Agent.from_llm_and_tools
     3. langchain.agents.agent.Agent.plan
     4. langchain.agents.agent.Agent.return_stopped_response
     5. langchain.agents.agent.AgentExecutor._acall
     6. langchain.agents.agent.AgentExecutor._atake_next_step
     7. langchain.agents.agent.AgentExecutor._call
     8. langchain.agents.agent.AgentExecutor._take_next_step
     9. langchain.agents.agent.LLMSingleActionAgent.aplan
    10. langchain.agents.agent.LLMSingleActionAgent.plan
    11. langchain.agents.agent_toolkits.nla.tool.NLATool.from_llm_and_method
    12. langchain.agents.agent_toolkits.openapi.planner._create_api_controller_agent
    13. langchain.agents.agent_toolkits.openapi.planner._create_api_controller_tool._create_and_run_api_controller_agent
    14. langchain.agents.agent_toolkits.openapi.toolkit.OpenAPIToolkit.from_llm
    15. langchain.agents.agent_toolkits.powerbi.base.create_pbi_agent
    16. langchain.agents.agent_toolkits.powerbi.chat_base.create_pbi_chat_agent
    17. langchain.agents.agent_toolkits.spark.base.create_spark_dataframe_agent
    18. langchain.agents.structured_chat.base.StructuredChatAgent.from_llm_and_tools
    19. langchain.chains.api.base.APIChain._acall
    20. langchain.chains.api.base.APIChain._call
    21. langchain.chains.api.openapi.chain.OpenAPIEndpointChain._call
    22. langchain.chains.base.Chain.__call__
    23. langchain.chains.base.Chain.acall
    24. langchain.chains.combine_documents.map_reduce.MapReduceDocumentsChain.acombine_docs
    25. langchain.chains.combine_documents.map_reduce.MapReduceDocumentsChain.collapse_document_chain
    26. langchain.chains.combine_documents.map_reduce.MapReduceDocumentsChain.combine_docs
    27. langchain.chains.combine_documents.map_reduce.MapReduceDocumentsChain.combine_document_chain
    28. langchain.chains.combine_documents.refine.RefineDocumentsChain.acombine_docs
    29. langchain.chains.combine_documents.refine.RefineDocumentsChain.combine_docs
    30. langchain.chains.combine_documents.stuff.StuffDocumentsChain.acombine_docs
    31. langchain.chains.combine_documents.stuff.StuffDocumentsChain.combine_docs
    32. langchain.chains.combine_documents.stuff.StuffDocumentsChain.prompt_length
    33. langchain.chains.constitutional_ai.base.ConstitutionalChain._call
    34. langchain.chains.conversational_retrieval.base.BaseConversationalRetrievalChain._acall
    35. langchain.chains.conversational_retrieval.base.BaseConversationalRetrievalChain._call
    36. langchain.chains.flare.base.FlareChain._call
    37. langchain.chains.flare.base.FlareChain._do_generation
    38. langchain.chains.flare.base.FlareChain._do_retrieval
    39. langchain.chains.flare.base.FlareChain.from_llm
    40. langchain.chains.llm.LLMChain._acall
    41. langchain.chains.llm.LLMChain._call
    42. langchain.chains.llm.LLMChain.aapply
    43. langchain.chains.llm.LLMChain.aapply_and_parse
    44. langchain.chains.llm.LLMChain.apply
    45. langchain.chains.llm.LLMChain.apply_and_parse
    46. langchain.chains.llm.LLMChain.apredict_and_parse
    47. langchain.chains.llm.LLMChain.predict_and_parse
    48. langchain.chains.llm_bash.base.LLMBashChain._call
    49. langchain.chains.loading._load_map_reduce_documents_chain
    50. langchain.chains.loading._load_stuff_documents_chain
    51. langchain.chains.mapreduce.MapReduceChain.from_params
    52. langchain.chains.pal.base.PALChain._call
    53. langchain.chains.qa_with_sources.base.BaseQAWithSourcesChain._acall
    54. langchain.chains.qa_with_sources.base.BaseQAWithSourcesChain._call
    55. langchain.chains.qa_with_sources.base.BaseQAWithSourcesChain.from_llm
    56. langchain.chains.qa_with_sources.loading._load_map_reduce_chain
    57. langchain.chains.question_answering._load_map_reduce_chain
    58. langchain.chains.retrieval_qa.base.BaseRetrievalQA._acall
    59. langchain.chains.retrieval_qa.base.BaseRetrievalQA._call
    60. langchain.chains.retrieval_qa.base.BaseRetrievalQA.from_llm
    61. langchain.chains.router.base.MultiRouteChain._acall
    62. langchain.chains.router.base.MultiRouteChain._call
    63. langchain.chains.router.multi_prompt.MultiPromptChain.from_prompts
    64. langchain.chains.router.multi_retrieval_qa.MultiRetrievalQAChain.from_retrievers
    65. langchain.chains.sequential.SimpleSequentialChain._acall
    66. langchain.chains.sequential.SimpleSequentialChain._call
    67. langchain.chains.sql_database.base.SQLDatabaseChain._call
    68. langchain.chains.sql_database.base.SQLDatabaseSequentialChain.from_llm
    69. langchain.chains.summarize._load_map_reduce_chain
    70. langchain.document_transformers.openai_functions.OpenAIMetadataTagger.transform_documents
    71. langchain.evaluation.loading.load_evaluators
    72. langchain.experimental.autonomous_agents.autogpt.agent.AutoGPT.run
    73. langchain.experimental.autonomous_agents.baby_agi.baby_agi.BabyAGI._call
    74. langchain.experimental.autonomous_agents.baby_agi.baby_agi.BabyAGI.execute_task
    75. langchain.experimental.cpal.base.CPALChain.from_univariate_prompt
    76. langchain.experimental.generative_agents.generative_agent.GenerativeAgent._generate_reaction
    77. langchain.experimental.generative_agents.generative_agent.GenerativeAgent.generate_dialogue_response
    78. langchain.experimental.generative_agents.generative_agent.GenerativeAgent.generate_reaction
    79. langchain.experimental.generative_agents.generative_agent.GenerativeAgent.summarize_related_memories
    80. langchain.experimental.generative_agents.memory.GenerativeAgentMemory.add_memories
    81. langchain.experimental.generative_agents.memory.GenerativeAgentMemory.add_memory
    82. langchain.experimental.generative_agents.memory.GenerativeAgentMemory.pause_to_reflect
    83. langchain.experimental.plan_and_execute.agent_executor.PlanAndExecute._call
    84. langchain.experimental.plan_and_execute.executors.agent_executor.load_agent_executor
    85. langchain.indexes.vectorstore.VectorStoreIndexWrapper.query
    86. langchain.indexes.vectorstore.VectorStoreIndexWrapper.query_with_sources
    87. langchain.memory.entity.ConversationEntityMemory.save_context
    88. langchain.memory.summary.ConversationSummaryMemory.from_messages
    89. langchain.model_laboratory.ModelLaboratory.from_llms
    90. langchain.output_parsers.fix.OutputFixingParser.parse
    91. langchain.output_parsers.retry.RetryOutputParser.parse_with_prompt
    92. langchain.output_parsers.retry.RetryWithErrorOutputParser.parse_with_prompt
    93. langchain.prompts.pipeline.PipelinePromptTemplate.format_prompt
    94. langchain.retrievers.contextual_compression.ContextualCompressionRetriever._aget_relevant_documents
    95. langchain.retrievers.contextual_compression.ContextualCompressionRetriever._get_relevant_documents
    96. langchain.retrievers.document_compressors.base.DocumentCompressorPipeline.acompress_documents
    97. langchain.retrievers.document_compressors.base.DocumentCompressorPipeline.compress_documents
    98. langchain.retrievers.document_compressors.chain_extract.LLMChainExtractor.compress_documents
    99. langchain.retrievers.document_compressors.chain_filter.LLMChainFilter.compress_documents
   100. langchain.retrievers.multi_query.MultiQueryRetriever.from_llm
   101. langchain.retrievers.multi_query.MultiQueryRetriever.retrieve_documents
   102. langchain.retrievers.self_query.base.SelfQueryRetriever._get_relevant_documents
   103. langchain.smith.evaluation.runner_utils._arun_on_examples
   104. langchain.smith.evaluation.runner_utils._construct_run_evaluator
   105. langchain.smith.evaluation.runner_utils._run_on_examples
   106. langchain.smith.evaluation.runner_utils.arun_on_dataset
   107. langchain.smith.evaluation.runner_utils.run_on_dataset
   108. langchain.tools.base.BaseTool.arun
   109. langchain.tools.base.BaseTool.run
   110. langchain.tools.powerbi.tool.QueryPowerBITool._arun
   111. langchain.tools.powerbi.tool.QueryPowerBITool._run
   112. langchain.tools.vectorstore.tool.VectorStoreQATool._run
   113. langchain.tools.vectorstore.tool.VectorStoreQAWithSourcesTool._run
   114. tests.integration_tests.chains.test_graph_database.test_cypher_generating_run
   115. tests.integration_tests.chains.test_graph_database.test_cypher_intermediate_steps
   116. tests.integration_tests.chains.test_graph_database.test_cypher_return_direct
   117. tests.integration_tests.chains.test_graph_database.test_cypher_save_load
   118. tests.integration_tests.chains.test_graph_database.test_cypher_top_k
   119. tests.integration_tests.chains.test_graph_database_sparql.test_sparql_insert
   120. tests.integration_tests.chains.test_graph_database_sparql.test_sparql_select
   121. tests.integration_tests.chains.test_memory.test_summary_buffer_memory_buffer_only
   122. tests.integration_tests.chains.test_memory.test_summary_buffer_memory_summary
   123. tests.integration_tests.chains.test_pal.test_colored_object_prompt
   124. tests.integration_tests.chains.test_pal.test_math_prompt
   125. tests.integration_tests.chains.test_react.test_react
   126. tests.integration_tests.chains.test_retrieval_qa.test_retrieval_qa_saving_loading
   127. tests.integration_tests.chains.test_self_ask_with_search.test_self_ask_with_search
   128. tests.integration_tests.chains.test_sql_database.test_sql_database_run
   129. tests.integration_tests.chains.test_sql_database.test_sql_database_run_update
   130. tests.integration_tests.chains.test_sql_database.test_sql_database_sequential_chain_intermediate_steps
   131. tests.integration_tests.chains.test_sql_database.test_sql_database_sequential_chain_run
   132. tests.integration_tests.retrievers.document_compressors.test_chain_extract.test_llm_chain_extractor
   133. tests.integration_tests.retrievers.document_compressors.test_chain_extract.test_llm_chain_extractor_empty
   134. tests.integration_tests.retrievers.document_compressors.test_chain_filter.test_llm_chain_filter
   135. tests.integration_tests.vectorstores.test_cassandra.test_cassandra_delete
   136. tests.unit_tests.agents.test_agent.test_agent_bad_action
   137. tests.unit_tests.agents.test_agent.test_agent_stopped_early
   138. tests.unit_tests.agents.test_agent.test_agent_tool_return_direct
   139. tests.unit_tests.agents.test_agent.test_agent_tool_return_direct_in_intermediate_steps
   140. tests.unit_tests.agents.test_agent.test_agent_with_callbacks
   141. tests.unit_tests.agents.test_react.test_predict_until_observation_normal
   142. tests.unit_tests.agents.test_react.test_react_chain
   143. tests.unit_tests.agents.test_react.test_react_chain_bad_action
   144. tests.unit_tests.agents.test_sql.test_create_sql_agent
   145. tests.unit_tests.chains.test_hyde.test_hyde_from_llm
   146. tests.unit_tests.chains.test_hyde.test_hyde_from_llm_with_multiple_n
   147. tests.unit_tests.chains.test_natbot.test_proper_inputs
   148. tests.unit_tests.chains.test_natbot.test_variable_key_naming
```

